Return-Path: <kasan-dev+bncBDVL3PXJZILBBMNZYCQAMGQEJNAPZQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id E43896B8BA6
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Mar 2023 08:05:22 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id p19-20020ac87413000000b003d2753047cbsf433007qtq.19
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Mar 2023 00:05:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678777521; cv=pass;
        d=google.com; s=arc-20160816;
        b=B+4jspuvXSvZm9rfeIepbfiqAsJXuNGH3g6dpTD7MKBdews8ITpmmjB9XDkywhhoPX
         zMT4m6zt+Pby1gO3edDOMPuovA4VrWEtZu6349wbv0l/KOyhCVm/atz706DkZVO1mIIY
         odHtnJr6vmitMaXPJkANVHQPGU8JQpTDKluJblgEVCCvr7avVmYf3FM+AWp+vl33K2bB
         wniAwcxBXPZc8Ncki1uknv74P6umvQB0mLqCzT1ZVBFrLXcEttyhiSDNX1wOBOZoO7m8
         q0gJS07YojRSVin18nzH7Jo4ilXZTeAfPxCAvWES2oiPbBNiV0/pJ7HTH70ZDokICOE9
         jpdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=oB7Df3tynYQ6bPsboNGMPS8pcNLkvdTHq7sDsquPpXw=;
        b=HXC1Gt/B/+3W8kB7tQpNqjiWiDc8Li/+OEo8I180abdkm1kTO8LEJZc1MAeBb7DBjX
         F4wSX4XgZYE/42HcirkG6gQghcThfjyba4BrxD9dxcSaO6S0KwnIBQh78ptSXIZV1BP6
         gW0weuPqqq7LgmFDSuUOARVSQV69ElzwME/QRyd9fi8twYP7ksCJTjW02boZpDk0n4DM
         DNJ+qgtHSLdz5kO+V3dcj1wsnKT5XsoEszZ8shCTSaSp55zSlWM3iYwzwFO9YthoqfZ6
         gGSnPulr1Q2I/LjrGwsdN559wAiyM/lWQQr9o3yqFel6Gai0awd0kdP0raym/GOl9Jja
         X9Ug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=GqSVXa1Z;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678777521;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=oB7Df3tynYQ6bPsboNGMPS8pcNLkvdTHq7sDsquPpXw=;
        b=K0Z3PwombMmkGIsTTq4sae8WFqwuuwD4VJg+VNjJo6dlf6q9OuA8H8Njj8gtZgjvJ1
         ysEMepygF9IJdQ51vO9qD9ga3oeIedJ98wtAKNwBRpbSPnEZQr0Frdpcsd28Wh2uBVBr
         KleMALoN2VLHZoRoPEOAbOfAG6UdyXAR/56wHmGK5nmgA+v52sMMKkqxaOxP4O4US6k1
         mhzMDuDfwygDcZiI4GH8THJ8WI8DW3cT30oG/QpzdAr5uIMa/e4P158fWq6aU2ByirBD
         RDx7Yu6WHVNE2jgXE5iH9zGrmFaKzpdmuWPWHDI0c4c810GLEXjDUKmCYY+F0N1xA9QF
         OMqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678777521;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=oB7Df3tynYQ6bPsboNGMPS8pcNLkvdTHq7sDsquPpXw=;
        b=eRucx/89/AVMSU5MxlSQ5lQHY6CgQZuT+uhf8TJISxrW92AELtPLaHEalbA+u20Cl8
         tfB4yIePh7MTkip2ysrK3OwDvutF3pSXKQloHLhNqgEzBNTmWIm74NQLeaz2LEKLkCNZ
         jQor7oJFaI5og4o1MfEuPgHufZk/un1LNNa628yU3cG0RBUAQdv7Zj0VAAiuPbtMB3CX
         vxqWEu1xyUjVWOQ0IZzY548phu7WylqqBDScB3wiPjkeZTEsrTb2I/PVw7Up3njcbvDJ
         +WEOOe33lUA0qKFiICz3yHXHGcNAWZKljAAuoPdxJlgUgrIpicACFWyJkhAs79XQvI2R
         KjHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWjleXANONzefTRHSkbropCapl3e7Ue5c+zKxWCSr0KNRG5Fb5z
	Lni3NxElU09kS8slLpeLSgc=
X-Google-Smtp-Source: AK7set+9z5LCaVxHePa4aU0k7eCcU902DytNwrkcLW6e06GiYGEeou1ysvkKuexwxXTYFSpQ0BrsOg==
X-Received: by 2002:a05:6214:14e9:b0:5ab:d0c:51af with SMTP id k9-20020a05621414e900b005ab0d0c51afmr724221qvw.6.1678777521575;
        Tue, 14 Mar 2023 00:05:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:4b82:b0:56e:94a0:dc66 with SMTP id
 qf2-20020a0562144b8200b0056e94a0dc66ls11319678qvb.11.-pod-prod-gmail; Tue, 14
 Mar 2023 00:05:21 -0700 (PDT)
X-Received: by 2002:a05:6214:d82:b0:5a7:a406:b9c1 with SMTP id e2-20020a0562140d8200b005a7a406b9c1mr11035319qve.47.1678777520907;
        Tue, 14 Mar 2023 00:05:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678777520; cv=none;
        d=google.com; s=arc-20160816;
        b=Un979sz7jO6AvOfjiptA/ZljLMUm0dTvXTK+HRtE2V2C9InLCArdI3rYoh7JthvULQ
         VD+jTNgRAHZ4sX3giNId+YsSpjwQXYeqjvyzipVbZY7GyoiSOLkD/qTjy5UNSsLoC/f3
         lKl8b9j8PML2oNiCFQwvXs5PUq4XSJHrwluj+oOpmu+SiGfQd52mXMnYjSXh2ka/grMR
         hwH/uAChzoyKnjyhJQVah0Mjdb1yhROChUJHs2pp23XBAWkxaeREQhzVNQwVzMX8LsHe
         /m0O2+kMk1Ng0VLAyvkV9k3IHjjtMtokz02aLH0/XY0ybfzkNbeYfZnBnVyR0QUxYSjm
         /k2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=tiUmcexDo0RBs7bw61Wmb4mvOXf5Hp4R+5QOCWVmynI=;
        b=mpPPlsrg3IYW9XO3dJEVcQ2VDYfWfQcSVNuTBf5Fx8sdoZMRW6HKZ/aJY1g71+iHV5
         Q9+OEN7a81qU36c26J3a1JY2XvvqrruRiWpRar6FzCDPUvwxKdOU2Ox1R51dwNFXjrQ5
         ZA5RNGcnf6TkiaSUZm8KSc96t9L9qOqvo8lyMI7PhJ7J1SQMFlqO0HxooWEGFjIS0x4O
         DKNr5j42Ux/KHCOQ/t8ZtoMJNqr+53TqxLN8sMwwHWceUln33CV0lpOB+CvnvCU1ojCL
         HJ3WVV8QJRDeVCFke3ITIaZ9jVzSsDnWC0jlJlitGGmPb8Gmwd8l7xLIcBC3sfyvbKE/
         7xIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=GqSVXa1Z;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id m4-20020a05620a13a400b0072ceb3a9fe4si86682qki.6.2023.03.14.00.05.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Mar 2023 00:05:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279871.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 32E3YQ8Q007143;
	Tue, 14 Mar 2023 07:05:16 GMT
Received: from nalasppmta05.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3pa3pttmwj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Mar 2023 07:05:16 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA05.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32E75EJA018045
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Mar 2023 07:05:14 GMT
Received: from zhenhuah-gv.qualcomm.com (10.80.80.8) by
 nalasex01a.na.qualcomm.com (10.47.209.196) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.986.41; Tue, 14 Mar 2023 00:05:10 -0700
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
To: <catalin.marinas@arm.com>, <will@kernel.org>, <glider@google.com>,
        <elver@google.com>, <dvyukov@google.com>, <akpm@linux-foundation.org>,
        <robin.murphy@arm.com>, <mark.rutland@arm.com>, <jianyong.wu@arm.com>,
        <james.morse@arm.com>, <wangkefeng.wang@huawei.com>
CC: Zhenhua Huang <quic_zhenhuah@quicinc.com>,
        <linux-arm-kernel@lists.infradead.org>, <kasan-dev@googlegroups.com>,
        <linux-mm@kvack.org>, <quic_pkondeti@quicinc.com>,
        <quic_guptap@quicinc.com>, <quic_tingweiz@quicinc.com>
Subject: [PATCH v8] mm,kfence: decouple kfence from page granularity mapping judgement
Date: Tue, 14 Mar 2023 15:05:02 +0800
Message-ID: <1678777502-6933-1-git-send-email-quic_zhenhuah@quicinc.com>
X-Mailer: git-send-email 2.7.4
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: BFosTgJeiPDhsjPCVbSXxpDRtTHdbmcX
X-Proofpoint-ORIG-GUID: BFosTgJeiPDhsjPCVbSXxpDRtTHdbmcX
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-13_13,2023-03-14_01,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 suspectscore=0 spamscore=0
 priorityscore=1501 malwarescore=0 mlxscore=0 clxscore=1015 phishscore=0
 impostorscore=0 adultscore=0 mlxlogscore=999 bulkscore=0
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2212070000 definitions=main-2303140059
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=GqSVXa1Z;       spf=pass
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
 arch/arm64/include/asm/kfence.h |  2 ++
 arch/arm64/mm/mmu.c             | 44 +++++++++++++++++++++++++++++++++++++++++
 arch/arm64/mm/pageattr.c        |  9 +++++++--
 include/linux/kfence.h          |  8 ++++++++
 mm/kfence/core.c                |  9 +++++++++
 5 files changed, 70 insertions(+), 2 deletions(-)

diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
index aa855c6..f1f9ca2d 100644
--- a/arch/arm64/include/asm/kfence.h
+++ b/arch/arm64/include/asm/kfence.h
@@ -10,6 +10,8 @@
 
 #include <asm/set_memory.h>
 
+extern phys_addr_t early_kfence_pool;
+
 static inline bool arch_kfence_init_pool(void) { return true; }
 
 static inline bool kfence_protect_page(unsigned long addr, bool protect)
diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
index 6f9d889..7fbf2ed 100644
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
@@ -525,6 +527,33 @@ static int __init enable_crash_mem_map(char *arg)
 }
 early_param("crashkernel", enable_crash_mem_map);
 
+#ifdef CONFIG_KFENCE
+
+static phys_addr_t arm64_kfence_alloc_pool(void)
+{
+	phys_addr_t kfence_pool;
+
+	if (!kfence_sample_interval)
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
@@ -543,6 +572,10 @@ static void __init map_mem(pgd_t *pgdp)
 	 */
 	BUILD_BUG_ON(pgd_index(direct_map_end - 1) == pgd_index(direct_map_end));
 
+	early_kfence_pool = arm64_kfence_alloc_pool();
+	if (early_kfence_pool)
+		memblock_mark_nomap(early_kfence_pool, KFENCE_POOL_SIZE);
+
 	if (can_set_direct_map())
 		flags |= NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
 
@@ -608,6 +641,17 @@ static void __init map_mem(pgd_t *pgdp)
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
index 726857a..570d4e3 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -64,6 +64,12 @@ static __always_inline bool is_kfence_address(const void *addr)
 void __init kfence_alloc_pool(void);
 
 /**
+ * kfence_set_pool() - allows an arch to set the
+ * KFENCE pool during early init
+ */
+void __init kfence_set_pool(phys_addr_t addr);
+
+/**
  * kfence_init() - perform KFENCE initialization at boot time
  *
  * Requires that kfence_alloc_pool() was called before. This sets up the
@@ -222,8 +228,10 @@ bool __kfence_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *sla
 
 #else /* CONFIG_KFENCE */
 
+#define KFENCE_POOL_SIZE 0
 static inline bool is_kfence_address(const void *addr) { return false; }
 static inline void kfence_alloc_pool(void) { }
+static inline void kfence_set_pool(phys_addr_t addr) { }
 static inline void kfence_init(void) { }
 static inline void kfence_shutdown_cache(struct kmem_cache *s) { }
 static inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags) { return NULL; }
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 5349c37..0765395 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -814,12 +814,21 @@ void __init kfence_alloc_pool(void)
 	if (!kfence_sample_interval)
 		return;
 
+	/* if the pool has already been initialized by arch, skip the below */
+	if (__kfence_pool)
+		return;
+
 	__kfence_pool = memblock_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
 
 	if (!__kfence_pool)
 		pr_err("failed to allocate pool\n");
 }
 
+void __init kfence_set_pool(phys_addr_t addr)
+{
+	__kfence_pool = phys_to_virt(addr);
+}
+
 static void kfence_init_enable(void)
 {
 	if (!IS_ENABLED(CONFIG_KFENCE_STATIC_KEYS))
-- 
2.7.4

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1678777502-6933-1-git-send-email-quic_zhenhuah%40quicinc.com.
