Return-Path: <kasan-dev+bncBDVL3PXJZILBBRW5XKQAMGQEFIBXSOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 8483C6B6EAF
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Mar 2023 06:04:08 +0100 (CET)
Received: by mail-io1-xd40.google.com with SMTP id l7-20020a0566022dc700b0074cc9aba965sf5729154iow.11
        for <lists+kasan-dev@lfdr.de>; Sun, 12 Mar 2023 22:04:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678683847; cv=pass;
        d=google.com; s=arc-20160816;
        b=UJUCtF+srM6AEJbgvojfwZfNXPe6mu2XLmk0io0oiqQ2WWEBAkwkgf6CQqjMNpbB3Y
         l3FEOZRuLFxgmch7a6ERX4hj3mb4dDHN41CCIWZDKCHmPFVGAeIY4/XPO4EwEujHiH/k
         ZHeuP2kSQuj3Ei0+0wB1nFcFHPVG2Xs5f6y28dvuZ58JRhLrbLb30sHYdszdJFqBtJ9f
         GwZrZSm51xhHQgip16rvJ1eIXKOaauE8eLmkY8ZZYiFfhv+q/YPLXaoVMYjtWv2bIGlT
         Bmdhn+N/xa79hSpesSKrLplPWbvYo+3gWx1ApXzmOhGxlmHlsN5sul67+qRlPVXmqXCb
         A9uA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=L6wrV8NAW9z5yCH4lDQKe+qkkRn13HkY6ufxeSXWDTQ=;
        b=g30MGXc/Qea5BYCc6PY/p0OssQYXpT4prmKeThIjf9gNOn1QCIq4PlCGLmAQ389FZM
         FJvxZ3DoMUQcMoeKkACFCqAwKA6gfFiya5FusFTNKKU0CrK2AyvZiuqGd6JNn2+YP+hh
         rIQhyj9kRQ5aigbZwCj3c++Ybl25PJ23PC2DuRhF+Q+8HbYyBCP0HzjDOWkBBboWHjuW
         pkWNcLMWLCcdCimMBKZPgGHeEJqtlkwf4NsUrYRZ6F8POn0gyyvHlIuLZ5UtL1Wno/Fg
         TigCXH7ahf/KRvq+Owv9g2C2ym3DFN3qRqYKvsiKu8S7s3DoZkuxSBAFErLOpIwt9Fwq
         FdaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=bDsJQFDw;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678683847;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=L6wrV8NAW9z5yCH4lDQKe+qkkRn13HkY6ufxeSXWDTQ=;
        b=T7Zf4Lyalrt8yz5eoB73qqfugr8qEWc/sRArTTTNjZ3aoiUUtX/yDO3ALLtuVTseuF
         XZRKh4DagTXAOk38RCROWd74+/UHzhtHtiixU3WMAF2x8c/NUIsbFzzk9EVGbIQXpLZY
         hIyt95kILAr+6uGWag3c5Bt8MhZRyuGH8z0t/41FRIYCQbvlIxNIT/u9TjV0RavBPgUH
         MaCzNg/CRD/sQKZEY/jp3veORys2rw/JfPDxwRaH9xDIDRBRviIs7zjntHhsJIKA0uJi
         06mLYZYVNKTJoHjbb0xliiYClO2G1VG1MQnLaSoJKcItFfbizaaiYlogkaYw85ybz32J
         AZAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678683847;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=L6wrV8NAW9z5yCH4lDQKe+qkkRn13HkY6ufxeSXWDTQ=;
        b=Zj04VStdf8YutquJUP+e0rt0M0Ygl7bQqUijVX1kLOt0jcGl+Ml5/25b5BnYtSW91a
         SVPrAvXpKTTE3X2ODKiTaRAduu3q7j+aKWRaLM4zailPxMr0j0pWrsWqDkdID94lduG6
         +Eq5Nhw2hZerw+od5qAjtAyPmHb7ZtbGGNYZAe66CkDmEP9E53CtER/+e3whRo0Q7eVr
         W5R+qyhiGiVWtDGsD/2NCfRMaAuz+4ytaojiKC0FgvLfCwJo8Em3ghx8zMItDS5NZwYs
         tWTC23+1ecfa2sfcDsDVUscdCYkIh1/SrGVKX5OWKzG91Uz2YdWK0ZUIO4W/Cyb6VDGr
         psbw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVwEWKROfS73Ghx4U7l3d2lhM+bhyYFofQe7eNL0oJeufvwwAby
	PkBaIXzcpjBZGeDrGYRuRkg=
X-Google-Smtp-Source: AK7set8unt4joUAPM/SH+nl9V1WBlcItojOeAuOXHeHyvha6eacYT1nKPu3+XuIpuobkhHBMJSNqsQ==
X-Received: by 2002:a02:94ab:0:b0:3a7:e46e:ab64 with SMTP id x40-20020a0294ab000000b003a7e46eab64mr16689425jah.1.1678683846977;
        Sun, 12 Mar 2023 22:04:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d148:0:b0:314:10d2:cf32 with SMTP id t8-20020a92d148000000b0031410d2cf32ls3480225ilg.7.-pod-prod-gmail;
 Sun, 12 Mar 2023 22:04:06 -0700 (PDT)
X-Received: by 2002:a05:6e02:1709:b0:316:e6e7:c124 with SMTP id u9-20020a056e02170900b00316e6e7c124mr13639439ill.15.1678683846487;
        Sun, 12 Mar 2023 22:04:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678683846; cv=none;
        d=google.com; s=arc-20160816;
        b=sUpSitHTwB0CsoEhZA3z72pbM1WrtLkGfG5nPdrSFW1sE4FVZUu5xKwTDH59rKiHz0
         CkzHwwoXYGAlqqB9FvR3ic3m2u85nXhWGqjRTFNwyN0UNPZhEYISkNNwfy/4S5gjvsfx
         OdF+9t+LtSJepnt1Vp1Lv3zWM+vO6B6LGoQjT0OrN6RAcVDfvm/2xAiMOF1/N8aMrEvA
         yJ67KX8xFD0+S03rfP+Rl4s4IgPT3eAco/HRqkusk73SDELDdMAjKe/dYAQzL+fQ6UZ6
         LSScN2QBgf+Hp94R4THvDMRjMbnuwf+hi+HhLwM3YWkFuOp2DTx0u1NlxppUG4qpFUPE
         vFAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=CeryZ7tZlQlJhqewejfy6u0bmLwteHR+Jp7YCP2Di8o=;
        b=PXTCR78agZM19hHcvyoXcDwPqy0bcaq5vWgji1tVB+p6iq52j/tXSTh6m40Ebm1/TC
         EhBt8vSt9yfg4meOFIg4dk9GsJRdPl5bbHsissVvpPMDw4B0wqzP2hC1KvJkCquNKE9Y
         JKAxdRVbZ5acI/Vh/2WEkCFFPOm7GgQG2SP52KXEsRdmJpfwuc3AiqqyO17UX0GuoD/j
         8SIonumiVfXFt7y6f1az04+1FFung/7MmQaH+gE7QTFeT65lZR4723uK9nl+jBPN3AI6
         NHbu0ctSXtBv2+qwgoevQMpKwUu1Rx06KONY7c+1ak/N9dPzmkjrd0kn5+ZqYV+EhGXz
         rUXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=bDsJQFDw;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0a-0031df01.pphosted.com (mx0a-0031df01.pphosted.com. [205.220.168.131])
        by gmr-mx.google.com with ESMTPS id u13-20020a05663825cd00b003e7efb1d848si764287jat.3.2023.03.12.22.04.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 12 Mar 2023 22:04:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) client-ip=205.220.168.131;
Received: from pps.filterd (m0279866.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 32D2j8V2023829;
	Mon, 13 Mar 2023 05:03:59 GMT
Received: from nalasppmta03.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3p8jxgbu2r-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 13 Mar 2023 05:03:58 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA03.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32D53wr7028703
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 13 Mar 2023 05:03:58 GMT
Received: from zhenhuah-gv.qualcomm.com (10.80.80.8) by
 nalasex01a.na.qualcomm.com (10.47.209.196) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.986.41; Sun, 12 Mar 2023 22:03:53 -0700
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
To: <catalin.marinas@arm.com>, <will@kernel.org>, <glider@google.com>,
        <elver@google.com>, <dvyukov@google.com>, <akpm@linux-foundation.org>,
        <robin.murphy@arm.com>, <mark.rutland@arm.com>, <jianyong.wu@arm.com>,
        <james.morse@arm.com>, <wangkefeng.wang@huawei.com>
CC: Zhenhua Huang <quic_zhenhuah@quicinc.com>,
        <linux-arm-kernel@lists.infradead.org>, <kasan-dev@googlegroups.com>,
        <linux-mm@kvack.org>, <quic_pkondeti@quicinc.com>,
        <quic_guptap@quicinc.com>, <quic_tingweiz@quicinc.com>
Subject: [PATCH v5] mm,kfence: decouple kfence from page granularity mapping judgement
Date: Mon, 13 Mar 2023 13:03:45 +0800
Message-ID: <1678683825-11866-1-git-send-email-quic_zhenhuah@quicinc.com>
X-Mailer: git-send-email 2.7.4
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01a.na.qualcomm.com (10.52.223.231) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: MO1973YtmlI57rI4ltRoGnB3M8FHdypl
X-Proofpoint-ORIG-GUID: MO1973YtmlI57rI4ltRoGnB3M8FHdypl
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-12_10,2023-03-10_01,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 bulkscore=0
 adultscore=0 suspectscore=0 mlxscore=0 malwarescore=0 clxscore=1015
 priorityscore=1501 mlxlogscore=999 spamscore=0 phishscore=0
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2212070000 definitions=main-2303130040
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=bDsJQFDw;       spf=pass
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
judgement was a bit over protected. From [1], Mark suggested to "just
map the KFENCE region a page granularity". So I decouple it from judgement
and do page granularity mapping for kfence pool only.

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
 arch/arm64/mm/mmu.c      | 42 ++++++++++++++++++++++++++++++++++++++++++
 arch/arm64/mm/pageattr.c |  5 ++---
 include/linux/kfence.h   |  8 ++++++++
 mm/kfence/core.c         |  9 +++++++++
 4 files changed, 61 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
index 6f9d889..ca5c932 100644
--- a/arch/arm64/mm/mmu.c
+++ b/arch/arm64/mm/mmu.c
@@ -24,6 +24,7 @@
 #include <linux/mm.h>
 #include <linux/vmalloc.h>
 #include <linux/set_memory.h>
+#include <linux/kfence.h>
 
 #include <asm/barrier.h>
 #include <asm/cputype.h>
@@ -525,6 +526,31 @@ static int __init enable_crash_mem_map(char *arg)
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
 static void __init map_mem(pgd_t *pgdp)
 {
 	static const u64 direct_map_end = _PAGE_END(VA_BITS_MIN);
@@ -532,6 +558,7 @@ static void __init map_mem(pgd_t *pgdp)
 	phys_addr_t kernel_end = __pa_symbol(__init_begin);
 	phys_addr_t start, end;
 	int flags = NO_EXEC_MAPPINGS;
+	phys_addr_t kfence_pool;
 	u64 i;
 
 	/*
@@ -564,6 +591,10 @@ static void __init map_mem(pgd_t *pgdp)
 	}
 #endif
 
+	kfence_pool = arm64_kfence_alloc_pool();
+	if (kfence_pool)
+		memblock_mark_nomap(kfence_pool, KFENCE_POOL_SIZE);
+
 	/* map all the memory banks */
 	for_each_mem_range(i, &start, &end) {
 		if (start >= end)
@@ -608,6 +639,17 @@ static void __init map_mem(pgd_t *pgdp)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1678683825-11866-1-git-send-email-quic_zhenhuah%40quicinc.com.
