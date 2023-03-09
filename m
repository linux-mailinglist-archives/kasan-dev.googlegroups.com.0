Return-Path: <kasan-dev+bncBDVL3PXJZILBB2P2U6QAMGQETK23SNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 5FA786B28F1
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Mar 2023 16:38:18 +0100 (CET)
Received: by mail-io1-xd38.google.com with SMTP id i2-20020a5d9e42000000b0074cfcc4ed07sf1038852ioi.22
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Mar 2023 07:38:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678376297; cv=pass;
        d=google.com; s=arc-20160816;
        b=iyVr0pwE1++JmwnUi3BwaLPbtPHlCWrYMdR1QShGe82xujP14mxJ1wynI5RhIsdGzz
         VkU+th5QyQJ7xlNHFKbKDc2wyxAZoA2nG58G4V2n/zszi85Pep+RoODc30Jr1Hcz6Olb
         A7loUF1vFQo25CeeJWQd+TPG/uATV+KdgfEzAc8smNKIQMa6BBAgK+ymvoBsWKDaDYW0
         OvtJaSyV9E/+Y91EXH6PWBGqxosnRKTRQxhbHdKp8/3yUxjF0cFwVevBdFAF6HcjLZ61
         cojoGkVWkX4ut7aYeQHa8oapVE64ZASEhzT7VDXPsAcqfNixf3OWS0gmV8dpxXKWN2IC
         6hCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=X7eq2qFEstSvQTtwN+ZrKsUnOerDa/q+xhjuCR9pzEE=;
        b=MjWA55VnqYT4L1ghs01B+GmXQrdtMxOc3A7AYLB9BA82tDN12cpyoc8HRqbxJd5iLO
         smIL1iHdfVUKzbeLd7/T1Z+Zc9rL0Jbnyhg9vYcO+oMnyWRGPp1GsxIk/azVGvfvxps5
         VZGaUQ4Ci3Hs8rEe0E2HB6Xlcac2p6UxBk1GPKBNAdTQfOfLUM+FcPmwrV4kotyXCMBE
         XHLTEljX8+k/5nCzOeA7HbLBfXeJsRx6WAHr2u4L4BZd4IFI7A8ZfDg2Lmiaa5e0dpfh
         4M3fE5wSP35/ZIswden/fVzcwJDkIPHoeZPUPx/tBgcSKY5PzwTwEzywmhNK72yC37Bu
         3ODQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=dd+ssvgd;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678376297;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=X7eq2qFEstSvQTtwN+ZrKsUnOerDa/q+xhjuCR9pzEE=;
        b=aZYiqll9uINgW2htHruj1QEpx69l1lnpiGCYarjMgn3B/HQ8aZARjrMvJ1forBGUfn
         XBFCway3NlatenarjcQYawaQI++MSSd3LB8V9O3uWs6u5v/E257b7GKc2BBfImDUVIUJ
         zmhQKe8hsd7fcmqApoysm/AP6EAQPlFZVGHQ9ThlY0jCOOE9+kcDdk3Um416N5l7YoLv
         NvdGP0LNdT5QU9fLaV8d6xrhmoGG1WGoPykqNufQifCXavzShKIW2JAxdruXFkHzGOI+
         0H5cbpus/CXZDHP749hqQEOjvpVgsGf44Ldvu1stqnAKkrZknqeAJkSUalfeeLlC5da0
         xpIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678376297;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=X7eq2qFEstSvQTtwN+ZrKsUnOerDa/q+xhjuCR9pzEE=;
        b=tZJaca0ypCYe7t66r92WG07Zu0mvk2yXL1iaWmPLIMRHccMjTxJkg3oZwkGrIrp8ly
         xTp3yO/QZb0+NJKiRKP2OwhDP4I+Re7NFyq8g/x0oxdD6w7+agBTpfFrbT8khXU2qxry
         3SXQ6J0Uh4acYyQpPrujEF2maoal+KATVWB0xJj8mfHRSbp1JHWZHPDn/aMEl+ZE8Irr
         ShZWfySIhUIGJG8V3koDAl3JiGZoifYlznPO6BLjFYFFxCi/G55lkyhDn4ZpATg/pJv6
         Zz8xREUfWLFgoI98aMa6kOAMStQx9F2BAFu09Tb3i6ZvPVGmmucNCYfo9CDnXueWxT3B
         uHkg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUYrXd6CKktJMjFQBKeaW9we2Tgff8/JKBqw27xtHjHpMmHQS+/
	STWR0TM7cHk0h0+5oWKf8yk=
X-Google-Smtp-Source: AK7set8QI3kq9++ha8BpbZSDOWejhmVOBkmW/6W8Q9hz5JxNWiWMSmdRbhIR7LTqtIvNAcIKlos11A==
X-Received: by 2002:a05:6602:22d1:b0:74a:f3d:3cc5 with SMTP id e17-20020a05660222d100b0074a0f3d3cc5mr10649544ioe.4.1678376297225;
        Thu, 09 Mar 2023 07:38:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d305:0:b0:317:96aa:2fb8 with SMTP id x5-20020a92d305000000b0031796aa2fb8ls527601ila.11.-pod-prod-gmail;
 Thu, 09 Mar 2023 07:38:16 -0800 (PST)
X-Received: by 2002:a92:1a43:0:b0:315:537e:4b18 with SMTP id z3-20020a921a43000000b00315537e4b18mr15661055ill.32.1678376296666;
        Thu, 09 Mar 2023 07:38:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678376296; cv=none;
        d=google.com; s=arc-20160816;
        b=myD9WH8xsu9tScebhe1E0Tlf5+Qfm0rJwaBuOa9+E0NUhXOc5jx+7IzJtpoYgR1JB/
         tK53lMphqt66hfFIL8nL9JjBjSenY+0rBZxc1LFi4Nop1VxumYDz4Xz7L6c6S0NSvOs/
         aPYnLZQfaP6m6ye0CqkA5ECBhOilE8ysk4nggpoTz6qpEDv4V7rBcGnCRPb+If1sqE7g
         777XrXqTOC1UjQFDyPRkFWnyTvnnG9NBUG7M+Qmr+R5fiZFjnecNgBQPbp0MBgDH7+WM
         F5miLeHyUPnPRmIXCwiMD3+ULpaeETdRBYiQA/3EwvdFSLeAgolXF3+5gL/LDNKFkDfB
         k2tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=BE74Oyq1lIbrbQ6rK7ltWUaDz+KLE2Idl+KU4pR1QCs=;
        b=n6dVeMg4/ZRQhCtS4NlJG7pgaRBY+0hSy71+DxZAwjbYvGiC0ywCU79abwvRmzLDoH
         hjeHTs3WR7wcKifSBSwT9mbhfNMWnhGhWy+eLEaizRa/y8IUdvsbFcbWhN9ZstDSF88i
         A1n7GEqKjzcK/U9ndujwK2cfhNqQ42Fc6fkMkYH7T72G84F1voF307osaCnQ6bGrmyDx
         7Nx2EQI5nDEKy1VMTZo2GCQOEk5lTQy8Sp6TUPOAPGINzfS1ynJ5xKZ/yyCNMJT7+zMq
         hOzXjn6w7n2cxF+hlQTUmS51zMSRpwzpHl0nYcKqM7fA5E4WVyymuv0f4WxSNlpf2MK2
         MiuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=dd+ssvgd;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0a-0031df01.pphosted.com (mx0a-0031df01.pphosted.com. [205.220.168.131])
        by gmr-mx.google.com with ESMTPS id r9-20020a056638130900b003f6e4b44e5csi1065138jad.6.2023.03.09.07.38.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Mar 2023 07:38:16 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) client-ip=205.220.168.131;
Received: from pps.filterd (m0279864.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 329CJNVP022185;
	Thu, 9 Mar 2023 15:38:10 GMT
Received: from nalasppmta03.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3p6vnakdmm-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 09 Mar 2023 15:38:09 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA03.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 329Fc9X2022664
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 9 Mar 2023 15:38:09 GMT
Received: from zhenhuah-gv.qualcomm.com (10.80.80.8) by
 nalasex01a.na.qualcomm.com (10.47.209.196) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.986.41; Thu, 9 Mar 2023 07:38:05 -0800
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
To: <catalin.marinas@arm.com>, <will@kernel.org>, <glider@google.com>,
        <elver@google.com>, <dvyukov@google.com>, <akpm@linux-foundation.org>,
        <robin.murphy@arm.com>, <mark.rutland@arm.com>, <jianyong.wu@arm.com>,
        <james.morse@arm.com>
CC: Zhenhua Huang <quic_zhenhuah@quicinc.com>,
        <linux-arm-kernel@lists.infradead.org>, <kasan-dev@googlegroups.com>,
        <linux-mm@kvack.org>, <quic_pkondeti@quicinc.com>,
        <quic_guptap@quicinc.com>, <quic_tingweiz@quicinc.com>
Subject: [PATCH v2] mm,kfence: decouple kfence from page granularity mapping judgement
Date: Thu, 9 Mar 2023 23:37:53 +0800
Message-ID: <1678376273-7030-1-git-send-email-quic_zhenhuah@quicinc.com>
X-Mailer: git-send-email 2.7.4
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: vm6nGviRVIoJS1M2bwWOC0TeX6rhGGyI
X-Proofpoint-ORIG-GUID: vm6nGviRVIoJS1M2bwWOC0TeX6rhGGyI
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-09_08,2023-03-09_01,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 bulkscore=0 adultscore=0
 spamscore=0 clxscore=1015 mlxlogscore=945 impostorscore=0 mlxscore=0
 phishscore=0 lowpriorityscore=0 suspectscore=0 malwarescore=0
 priorityscore=1501 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2212070000 definitions=main-2303090123
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=dd+ssvgd;       spf=pass
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
 include/linux/kfence.h   |  7 +++++++
 mm/kfence/core.c         |  9 +++++++++
 4 files changed, 62 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
index 6f9d889..46afe3f 100644
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
+		return 0;
+
+	kfence_pool = memblock_phys_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
+	if (!kfence_pool) {
+		pr_err("failed to allocate kfence pool\n");
+		return 0;
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
index 726857a..d982ac2 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -64,6 +64,11 @@ static __always_inline bool is_kfence_address(const void *addr)
 void __init kfence_alloc_pool(void);
 
 /**
+ * kfence_set_pool() - KFENCE pool mapped and can be used
+ */
+void __init kfence_set_pool(phys_addr_t addr);
+
+/**
  * kfence_init() - perform KFENCE initialization at boot time
  *
  * Requires that kfence_alloc_pool() was called before. This sets up the
@@ -222,8 +227,10 @@ bool __kfence_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *sla
 
 #else /* CONFIG_KFENCE */
 
+#define KFENCE_POOL_SIZE 0
 static inline bool is_kfence_address(const void *addr) { return false; }
 static inline void kfence_alloc_pool(void) { }
+static inline void kfence_set_pool(phys_addr_t addr) { }
 static inline void kfence_init(void) { }
 static inline void kfence_shutdown_cache(struct kmem_cache *s) { }
 static inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags) { return NULL; }
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 5349c37..a17c20c2 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -814,12 +814,21 @@ void __init kfence_alloc_pool(void)
 	if (!kfence_sample_interval)
 		return;
 
+	/* if __kfence_pool already initialized in some arch, abort */
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1678376273-7030-1-git-send-email-quic_zhenhuah%40quicinc.com.
