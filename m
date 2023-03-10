Return-Path: <kasan-dev+bncBDVL3PXJZILBBOPRVOQAMGQELOZVHYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 26DFD6B3A75
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Mar 2023 10:30:35 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id t12-20020aa7938c000000b005ac41980708sf2594990pfe.7
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Mar 2023 01:30:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678440633; cv=pass;
        d=google.com; s=arc-20160816;
        b=IrpGWdzsNpRQuecqad7Qh4d4m4U86P7l6en+D+HivCSwEIVYVjbM7s5dAZpfmf/nwm
         kbMI1zS6yRMFEc9Oqu2AjyJlWagFDnJST/coxhSzeq6otQpm7PZFT2dZ17/KDdUSibvB
         U2lhIdxTGCi8QZcwLsjgMAKrlo/7+p2tVXeqYXKPyZuacXYlgtUkYQc4oh0qm174PYPw
         KAm0yYHPdysx/C4uE2tarzrFSqyaVTtdTbjU4GLe20zh3isS7EheOA5LN4ufpJwZNSs+
         EZKR9VhL/ja/5gUvZDAt0iiHTjNolWywAkIe1Hy8z4odAeChHiAnCzfqKSHtcYBIEkuR
         iJtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=+w64om3BAayLuUskSwBlJWJtakadkLP2l1QLnsyFRcI=;
        b=s1k5n/pN3dF7aYzPKJ3Kkp0V8oq8n7mtIZ4qSEUKC2SxLBKvV+HMJiOKlSOrT/ZqwG
         0zvZ4yREupznxRyOsuJn5zF8OkQx04bQFn8s7kimFBlXPdi4Zw/RjWcTCmZKTOjw+AYl
         hG/RB9MJvY89EbERQ0y4a19/izO6MbXjcgV92YHoeLTVlEzKbXxhz4yxEe5bVj/5bfLE
         sbz10kvF9HRuTur54Gv2GRqne36vMuHYQJqxQD9eK5znh49JbnOmomP1YUQ40+j8FQ86
         OcnF5XU+GRwUb7k1ra95Dwcw4hNsFaw9uAS+omFVhtCp70T7CA9S58Ib16eA384NCcIO
         Tq3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=nFWqdgoa;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678440633;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+w64om3BAayLuUskSwBlJWJtakadkLP2l1QLnsyFRcI=;
        b=byW7IKpQqAwHOS/buDmjJbgorP5iGf3YCYMwGY9mFktRtfdudYbjswyIbCjlzyuffD
         JtAEtOjnOtuexPc7PFYNswPv/rF/WTz6l536A/nEMOfACd0KxxYzJwzr3MoGFRmRu0Jl
         +2bhoR+PMbVtjYW6speuB2q6h3RJNnD30D8sDYo3HI2nnspqxJa1NyCEmeZEVLKJkD6k
         DNj53556mhOCtfh0PtmRNUoxOgxKO6zQABJtBNJEvJc+wVdIrHBLudg90Q3U9kT1t4w1
         7efGuKHy9p8v0lVHh0J3Yk639+09Uswh43zIFVF1aaRdYl8DFO5+lkuecifK6UM6gTnJ
         d57A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678440633;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=+w64om3BAayLuUskSwBlJWJtakadkLP2l1QLnsyFRcI=;
        b=EtzEf8NcqzXlauWStz4yEPBGrd7ceigokVHuk+FEj7sRZvGMhDuqlPd12tge64hY8+
         MsF5lkgUWrTtNks5g4C5MyaUYxKC01rie6o1b1woeveU9q0WtNQhhrkDg7MnWTgroI/2
         MPSbfOuy5VDU8xa5OmqS4Jb6K7px6/5PPge7KjeJHKn1m/GkCG1Ry7GZFy6Wu1glYlDM
         +Ugn8at7FuHBe4ZBfSW+Yu02C4RmOxkFQJUAv/DmkBux2lbMak1MCQivw5nKHpypL1IV
         U3xKel/X2y6JFazkrjkn51o8FG8tAIFO/DjlgFTluGdp5p0E1fPPxFljgxLEn82fAcon
         qLig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUUherTtKxsFAUa1f9dme7CFCjL0jl1+fpKhsVQE9jbUV0kmqrL
	6ow5r3hyiXLf3Ee07OpbHXY=
X-Google-Smtp-Source: AK7set9zk90pc70dY3tqYbUHz5VKQvimAuPjtQRzqV9oKQDULoAq84ndzKkNcaDsYnVxuVg9JMcmwQ==
X-Received: by 2002:a17:90a:2aca:b0:237:5c37:d9ca with SMTP id i10-20020a17090a2aca00b002375c37d9camr9326381pjg.4.1678440633269;
        Fri, 10 Mar 2023 01:30:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:eb85:b0:199:182b:34bf with SMTP id
 q5-20020a170902eb8500b00199182b34bfls4814765plg.3.-pod-prod-gmail; Fri, 10
 Mar 2023 01:30:31 -0800 (PST)
X-Received: by 2002:a17:902:e744:b0:19c:d169:cb3f with SMTP id p4-20020a170902e74400b0019cd169cb3fmr31490991plf.21.1678440631788;
        Fri, 10 Mar 2023 01:30:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678440631; cv=none;
        d=google.com; s=arc-20160816;
        b=rkbri2RZ4QALlmi1V2fT9gIxFZ7qaGoDJRnYcg5yI3ybhoc37ghT36p4l0hFKQfQsi
         LNT+P1yfRSUuuPVoABhTclsyuxzxRRKgPR1gU6DXWAg7Fn7kEYZWAF2lfQOuYiGqEdRa
         Z7VN6C4tS07TEnaX09/yP4DUQVjReK2Hemv9Yn2rIuwZHjPglUkw4Ewf8BbM/janBQgp
         Scdw3LjfCTqTOJoI5O+Ebf8fTlCVc23Ml5H1xW/zlV1c26dnAEPR6jezJPUbZFKZk1R7
         I4w3meFahgmx1pVKxbziYJY/2LTXZdd2cRWDSZi/so1cs+f5Xf3NQNPweCsUlyopgsvI
         fC9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=tnEL3oCBzCfkJDbY5JlfL0dj9i+4DIeoKa3aJ04N4kc=;
        b=JuDcPh93YlVu+nZTi/L04jRigaSJoMhrB06dIXbIGnP6W4of/zZf1SfBdZlEk9813e
         a50KhYLwITGsjwcE2V7TECy2/DICBxO5fNY/RKnKyFDyDVlGqX4N+GAoqljr+f2lhEZ+
         NXiYDSG5Th5qaFg8lETIXAkD799eir6f/wPTXDgiw8vMtMF4pjGJuvkfQAGI45B4EzNf
         T4A9Mktc/SoVagtbj6Ar6+8t0bhoo6ItaRodNPywbTQbeqS22XT8dC6PXcDsoFoU+pvv
         VIfL60XeUGF5SXL2jGZT64ueZuPX4p9dLYfNGEMXguUs9S39bYugLXnjj2DE0fk5KIY2
         pjqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=nFWqdgoa;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0a-0031df01.pphosted.com (mx0a-0031df01.pphosted.com. [205.220.168.131])
        by gmr-mx.google.com with ESMTPS id e18-20020a170902ef5200b0019ef48fda11si87112plx.12.2023.03.10.01.30.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 10 Mar 2023 01:30:31 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) client-ip=205.220.168.131;
Received: from pps.filterd (m0279867.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 32A4vt6Z027894;
	Fri, 10 Mar 2023 09:30:24 GMT
Received: from nalasppmta03.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3p7bvk3jw7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 10 Mar 2023 09:30:24 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA03.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32A9UN3v019608
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 10 Mar 2023 09:30:23 GMT
Received: from zhenhuah-gv.qualcomm.com (10.80.80.8) by
 nalasex01a.na.qualcomm.com (10.47.209.196) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.986.41; Fri, 10 Mar 2023 01:30:19 -0800
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
To: <catalin.marinas@arm.com>, <will@kernel.org>, <glider@google.com>,
        <elver@google.com>, <dvyukov@google.com>, <akpm@linux-foundation.org>,
        <robin.murphy@arm.com>, <mark.rutland@arm.com>, <jianyong.wu@arm.com>,
        <james.morse@arm.com>
CC: Zhenhua Huang <quic_zhenhuah@quicinc.com>,
        <linux-arm-kernel@lists.infradead.org>, <kasan-dev@googlegroups.com>,
        <linux-mm@kvack.org>, <quic_pkondeti@quicinc.com>,
        <quic_guptap@quicinc.com>, <quic_tingweiz@quicinc.com>
Subject: [PATCH v4] mm,kfence: decouple kfence from page granularity mapping judgement
Date: Fri, 10 Mar 2023 17:30:04 +0800
Message-ID: <1678440604-796-1-git-send-email-quic_zhenhuah@quicinc.com>
X-Mailer: git-send-email 2.7.4
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01a.na.qualcomm.com (10.52.223.231) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: vrVYIJ-qG-r_JQDxJJIMqmFiDQ5tYfxj
X-Proofpoint-ORIG-GUID: vrVYIJ-qG-r_JQDxJJIMqmFiDQ5tYfxj
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-10_03,2023-03-09_01,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 bulkscore=0 impostorscore=0
 malwarescore=0 phishscore=0 spamscore=0 clxscore=1015 adultscore=0
 mlxlogscore=999 lowpriorityscore=0 mlxscore=0 suspectscore=0
 priorityscore=1501 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2212070000 definitions=main-2303100072
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=nFWqdgoa;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1678440604-796-1-git-send-email-quic_zhenhuah%40quicinc.com.
