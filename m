Return-Path: <kasan-dev+bncBDVL3PXJZILBBSM7VKQAMGQE63JPRRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 19FE36B33EB
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Mar 2023 03:02:51 +0100 (CET)
Received: by mail-qk1-x73f.google.com with SMTP id x14-20020ae9e90e000000b007429af46d5esf2274668qkf.12
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Mar 2023 18:02:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678413769; cv=pass;
        d=google.com; s=arc-20160816;
        b=bek4AM1JEv7mxPC3M7atLgbpmNMO9e4qkmeJb1x9bzN1zWNC445GFg8I0j0cmsq8Qt
         jJjKeStVkFOw0x3Ah3el0/lbSWBK+B+CoIPP3rbhxyyVCz8q73RojxBVNZajqFV3uEkW
         czc2Rqk+/S8dUHViEQi7nAiAPxpiwf17mUAYAPB9J6uOdRQEOmILL5vjY50h7Hw4IPCz
         A88aqVvZ6a8ozI6rKOtEiGc968pnvMP/iJSH+tNf6zLR22dx9cayImJfd6JUXbhiB8Qh
         OwvA3GYIWnZ7knhB6tDnzL8NGYWApVEJXYYZFp1ZjI+8U1rjGLw0UxLjQpjsFy30XE1z
         +1cA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=t4Q+WeMVAU28lb0/QdMWYYthvn25J2WKMYq3eCJPAFc=;
        b=HvJUMa2XtWfjdH8l/sxaH8u3FqUjIteeN3TllIR9CuAZP2T2nlj7p3ByNot3bsf8m4
         HOZteOyh83Z/tI3vPtvmzdiP1kCcubbNMLptRFjkmR+gDimuUbWXmeUJ55juMHWaPak5
         DdpZG4ekhvViW/WLlS0eQQiPEj3W0Kp99P9taP49uoEJG6J/OSmPsQXAmv9/Re0UjJFA
         pi6iSQ4G3u+R6xb0fB5J70f4KazgF1FbSGUd0+/rl36k8v3CQuxci1fQZ3TQrqI33vVx
         xCt8xy2hUoF+ybduw4XJi2R72wJQKfn4VxVW4zAEcyICbGKuW0nc4PY5ZxeoVjsXUE+s
         9v9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=X8i8VNk1;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678413769;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=t4Q+WeMVAU28lb0/QdMWYYthvn25J2WKMYq3eCJPAFc=;
        b=fHl/JTHBU82bhhaQMTWF8rXGN9i9PHA6NBo7RYkPOayBFq77dx7M2kOKv2dNgi9WrB
         IIVB8EZurmIpD39NFC5BgDptnFxOjxSSvqPMnrRD55TFC+0W93UidGZkggZrmsL4Llkz
         I62DCCGRKPs0m52a6BfvudREyj5HsluFaH9/rciSpZVzd9e54p6N12S1vFIeiQkYZMl3
         yCDMU43X6uh2q6zQCs13Tu0RUHhtyGc/tLHBSGcbuMoPjeT70G7DcmNRgRkqK4v6XNeF
         +MRkgD8wyrlAQs+r23BpnXVDCULA75Pe3UsNcYaxrKxMD/DKDgiUjJTKD78snXi189z/
         oAzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678413769;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=t4Q+WeMVAU28lb0/QdMWYYthvn25J2WKMYq3eCJPAFc=;
        b=cWrZz+Oy5Mctwgs/nG7WW3uuNr12tY0R1UDm6CCiYqeixbJ37U9DtSwC17cw3BRV4Y
         +fGaE/m0HkAU87dJubV8NK3Jsob56LmOmZd7NLNLogxHiSkN4hzXcV89fE3aeiwjnQsc
         NZ9cQtySTOg1gRAosNPQfwKyV9beMK3EMTasT9Ye9GRk+GlqnQQQ+uQOFbfZ1U2pz0SW
         y14trpv5ckMu7rvcP/8xfscEdfrGm70Ug23M1rETHagmmMKBOhFGVbPyKpjDVaSxcVAi
         1rRXLyyjeQsMUhX/6Ru5btfhVqRhfx8vZrIUPf+t0FH6aTaT0N+uHJySdDca0DW0mUkC
         7ypQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUtuBAKzFeOS15hll7/nAn6V18P0NnPhbZOkYB1ooQT7z48386I
	YBXl0T6KdAIJBaXiRHccDZE=
X-Google-Smtp-Source: AK7set8AU5w3pXQ8RfVCGr4OSpZGUyRx0vY+ceHwcs11ySTXTZDOD9j6OK94Dgtv8mjqCJYXYAihEA==
X-Received: by 2002:ac8:42ce:0:b0:3bf:fe84:9ca0 with SMTP id g14-20020ac842ce000000b003bffe849ca0mr6878712qtm.12.1678413769641;
        Thu, 09 Mar 2023 18:02:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4a9a:0:b0:3b9:bfda:1fa8 with SMTP id l26-20020ac84a9a000000b003b9bfda1fa8ls4223236qtq.3.-pod-prod-gmail;
 Thu, 09 Mar 2023 18:02:49 -0800 (PST)
X-Received: by 2002:ac8:7d4c:0:b0:3bf:cf7f:a298 with SMTP id h12-20020ac87d4c000000b003bfcf7fa298mr9086014qtb.57.1678413769100;
        Thu, 09 Mar 2023 18:02:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678413769; cv=none;
        d=google.com; s=arc-20160816;
        b=lkzb/MAEq+b34Vm5UCh91pv7GmLIYKr/UFYu4U/UJmQrZsVhjiywZI5c2V0Syjzpcv
         LtuSZUoSuaD6Qlek2q6IVjNrLug0npkWcLpjm2CWxNenxku3sHj6v3hwMoZTPxjtdBrG
         8gwfBcDP5YxYY/URrKOroRzqP8hbAVpdjKucM8vyCQVODijm3EApafTkpKxuO5TwIVjs
         7K7/YmE09RUdVozGBf9hKlMKi/FGeHdVrurth/h/rT1cwt5DJKfzTPy7YajVf6XoCD6V
         E39VSfZEAa//RFazhTU72dtt/Pd50QHKg5M3ObM12BfHpF95naJwnyVYfVzFxtM/+Pmf
         S0dg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=0mJOpa9VaFUTf+BH+6m3OJhsLSFyi5AnZCvaQh3z86k=;
        b=UOCF+GmmieS/sRFojAYBTBtKUWMmhmlBUum2EVloRmUTmGU9SLPXt9237uWan4ndbB
         bwB9iYRFPJrYAnFOigPGfIUCDo6UaSO61Z4f1QzWJXUkCWXhEKRCcJSJZVVh39uEKSSc
         hkbQZwmVw0jp5apwj0BkXZeoGIASKzp+HCCNzPyBv6Gxrhj931opubLMKEsMEBEz0cDY
         IfHiBohOGPrNYu8LY7DZ5hH9NVdANlBo71HaoOK2gCW4XEMOVeIwJk6nSuKv5CWFSQuf
         vs7BZaZERZyzgQNrqyr58sOI2vySAy2C6zXsr58fCEXCK/ekO0NVICrjkp16Wyss/fLs
         Z3rw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=X8i8VNk1;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id c40-20020a05620a26a800b0072ceb3a9fe4si21862qkp.6.2023.03.09.18.02.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Mar 2023 18:02:49 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279871.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 32A18Thk020815;
	Fri, 10 Mar 2023 02:02:44 GMT
Received: from nalasppmta04.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3p7rqgrbv9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 10 Mar 2023 02:02:44 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA04.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32A22hrY027661
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 10 Mar 2023 02:02:43 GMT
Received: from zhenhuah-gv.qualcomm.com (10.80.80.8) by
 nalasex01a.na.qualcomm.com (10.47.209.196) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.986.41; Thu, 9 Mar 2023 18:02:39 -0800
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
To: <catalin.marinas@arm.com>, <will@kernel.org>, <glider@google.com>,
        <elver@google.com>, <dvyukov@google.com>, <akpm@linux-foundation.org>,
        <robin.murphy@arm.com>, <mark.rutland@arm.com>, <jianyong.wu@arm.com>,
        <james.morse@arm.com>
CC: Zhenhua Huang <quic_zhenhuah@quicinc.com>,
        <linux-arm-kernel@lists.infradead.org>, <kasan-dev@googlegroups.com>,
        <linux-mm@kvack.org>, <quic_pkondeti@quicinc.com>,
        <quic_guptap@quicinc.com>, <quic_tingweiz@quicinc.com>
Subject: [PATCH v3] mm,kfence: decouple kfence from page granularity mapping judgement
Date: Fri, 10 Mar 2023 10:02:30 +0800
Message-ID: <1678413750-6329-1-git-send-email-quic_zhenhuah@quicinc.com>
X-Mailer: git-send-email 2.7.4
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01a.na.qualcomm.com (10.52.223.231) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-ORIG-GUID: GLaDBenbvNYnm4lBuWxOtpsQlQrdptk-
X-Proofpoint-GUID: GLaDBenbvNYnm4lBuWxOtpsQlQrdptk-
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-09_14,2023-03-09_01,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 phishscore=0 impostorscore=0
 adultscore=0 mlxlogscore=999 spamscore=0 clxscore=1015 malwarescore=0
 priorityscore=1501 suspectscore=0 mlxscore=0 lowpriorityscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2212070000 definitions=main-2303100011
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=X8i8VNk1;       spf=pass
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

Kfence only needs its pool to be mapped as page granularity, previous
judgement was a bit over protected. Decouple it from judgement and do
page granularity mapping for kfence pool only [1].

To implement this, also relocate the kfence pool allocation before the
linear mapping setting up, arm64_kfence_alloc_pool is to allocate phys
addr, __kfence_pool is to be set after linear mapping set up.

LINK: [1] https://lore.kernel.org/linux-arm-kernel/1675750519-1064-1-git-send-email-quic_zhenhuah@quicinc.com/T/
Suggested-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Zhenhua Huang <quic_zhenhuah@quicinc.com>
---
 arch/arm64/mm/mmu.c      | 44 ++++++++++++++++++++++++++++++++++++++++++++
 arch/arm64/mm/pageattr.c |  5 ++---
 include/linux/kfence.h   |  8 ++++++++
 mm/kfence/core.c         |  9 +++++++++
 4 files changed, 63 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
index 6f9d889..9f06a29e 100644
--- a/arch/arm64/mm/mmu.c
+++ b/arch/arm64/mm/mmu.c
@@ -24,6 +24,7 @@
 #include <linux/mm.h>
 #include <linux/vmalloc.h>
 #include <linux/set_memory.h>
+#include <linux/kfence.h>
 
 #include <asm/barrier.h>
 #include <asm/cputype.h>
@@ -525,6 +526,33 @@ static int __init enable_crash_mem_map(char *arg)
 }
 early_param("crashkernel", enable_crash_mem_map);
 
+#ifdef CONFIG_KFENCE
+
+static phys_addr_t arm64_kfence_alloc_pool(void)
+{
+	phys_addr_t kfence_pool = 0;
+
+	if (!kfence_sample_interval)
+		return (phys_addr_t)NULL;
+
+	kfence_pool = memblock_phys_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
+	if (!kfence_pool) {
+		pr_err("failed to allocate kfence pool\n");
+		return (phys_addr_t)NULL;
+	}
+
+	return kfence_pool;
+}
+
+#else
+
+static phys_addr_t arm64_kfence_alloc_pool(void)
+{
+	return (phys_addr_t)NULL;
+}
+
+#endif
+
 static void __init map_mem(pgd_t *pgdp)
 {
 	static const u64 direct_map_end = _PAGE_END(VA_BITS_MIN);
@@ -532,6 +560,7 @@ static void __init map_mem(pgd_t *pgdp)
 	phys_addr_t kernel_end = __pa_symbol(__init_begin);
 	phys_addr_t start, end;
 	int flags = NO_EXEC_MAPPINGS;
+	phys_addr_t kfence_pool = 0;
 	u64 i;
 
 	/*
@@ -564,6 +593,10 @@ static void __init map_mem(pgd_t *pgdp)
 	}
 #endif
 
+	kfence_pool = arm64_kfence_alloc_pool();
+	if (kfence_pool)
+		memblock_mark_nomap(kfence_pool, KFENCE_POOL_SIZE);
+
 	/* map all the memory banks */
 	for_each_mem_range(i, &start, &end) {
 		if (start >= end)
@@ -608,6 +641,17 @@ static void __init map_mem(pgd_t *pgdp)
 		}
 	}
 #endif
+
+	/* Kfence pool needs page-level mapping */
+	if (kfence_pool) {
+		__map_memblock(pgdp, kfence_pool,
+			kfence_pool + KFENCE_POOL_SIZE,
+			pgprot_tagged(PAGE_KERNEL),
+			NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
+		memblock_clear_nomap(kfence_pool, KFENCE_POOL_SIZE);
+		/* kfence_pool really mapped now */
+		kfence_set_pool(kfence_pool);
+	}
 }
 
 void mark_rodata_ro(void)
diff --git a/arch/arm64/mm/pageattr.c b/arch/arm64/mm/pageattr.c
index 79dd201..61156d0 100644
--- a/arch/arm64/mm/pageattr.c
+++ b/arch/arm64/mm/pageattr.c
@@ -22,12 +22,11 @@ bool rodata_full __ro_after_init = IS_ENABLED(CONFIG_RODATA_FULL_DEFAULT_ENABLED
 bool can_set_direct_map(void)
 {
 	/*
-	 * rodata_full, DEBUG_PAGEALLOC and KFENCE require linear map to be
+	 * rodata_full and DEBUG_PAGEALLOC require linear map to be
 	 * mapped at page granularity, so that it is possible to
 	 * protect/unprotect single pages.
 	 */
-	return (rodata_enabled && rodata_full) || debug_pagealloc_enabled() ||
-		IS_ENABLED(CONFIG_KFENCE);
+	return (rodata_enabled && rodata_full) || debug_pagealloc_enabled();
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1678413750-6329-1-git-send-email-quic_zhenhuah%40quicinc.com.
