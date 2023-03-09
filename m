Return-Path: <kasan-dev+bncBDVL3PXJZILBBWFGU2QAMGQEMOS2DXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id 686D16B1D49
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Mar 2023 09:05:46 +0100 (CET)
Received: by mail-ua1-x93d.google.com with SMTP id c24-20020ab023d8000000b006907ba8c229sf447922uan.23
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Mar 2023 00:05:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678349145; cv=pass;
        d=google.com; s=arc-20160816;
        b=mHJgBVn4d62EIj/987P4q+K14Xp1ssbv+1eZhCxpMiPph3wcgPlJywy2u0/oOkdK2v
         gY8fM918eCnapDIjjpbCrS/JzfkYdG1F/n2L4RWn3Bpj6X47DYNKDy8tUaNgFhMk5eZ5
         vW2mkNXb0jydzNZvFVB9Si0Cs+d3WkGeO61tWoYyOpE2/FwnQ9avwwM076viT9A32aaV
         NKJqJc720QM6RTzCrdOFZPL3bhK/WKCAPX7G5Aec6i2m7JruCtSUETJMtH8nn4H2mz+l
         /YY/jRbgoB6fmxcclv22LDD9m2doj+NaBS/HitjlPEHUnhRiFJu1lbR3vEqud5lMVej1
         txYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=weG6BElBT/qTbUBxLYcoOaARtxD1Hw9OqIeObqmUhuE=;
        b=whNYWDQm1jg2mXT56ovSiHRUaGbVp8Llexb72c7JcR7wh3k8DRtRa9NycqOpYXlg+L
         LAy3EVmG5M76pkzu4ygp1TCIlaQOfue+ZQz2dNdcdGzosMWHzS/Sdl40UJ58GLHaCQJX
         W7gJIrCSn5kResM6Z5Ctqa6KKJSJmxlUe09ARwqJAz8y1/MIWNIE3z0D97aiSchaZ4xi
         ZDuQCMufgBzy4ZLvxpaM+xSm6qKeYlWs+tko2MZCIrKIABuLH1zruBh9iBm6Bm0hzSWD
         V/xzVfdS7zEaKzhWCtoqxDULGI9PJCg0L/YJGsLLKwBbi4jRwWXPRXy1zgEQ7ijjzw9H
         Cg9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=nscrAZx+;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678349145;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=weG6BElBT/qTbUBxLYcoOaARtxD1Hw9OqIeObqmUhuE=;
        b=fO+i19ofx5SIHr+tVFNdtYXjaLm2uvHrRw4z8AK0GGEjIl48ZMCvXTD/bJTU2IHx6I
         cBfdTc+qhKJXqpuN/E4LZlDt6SrP5oSGN7+8vMn4I22GgcrgWFUPXKjY/KhFNkHDI1xX
         Aa8CkisFo+rtYSjX8Wr6qIAkQn4Sd8/U71HatRA3rAcUZVHnVn0Qg+P6ke37EZdyvIPO
         9f8LuuNXPABsP9d1CaCxritl8+vL1zEfeavxxWdZ99UX/8zeGd70HM5cFAyqNq87bbp/
         G2lzRZ8+a6vXqhlz/oU257PntxIWuT3Qq7mn7Al9GXyN+6V6zzr4uOMduFsc6+PUCGiC
         fp3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678349145;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=weG6BElBT/qTbUBxLYcoOaARtxD1Hw9OqIeObqmUhuE=;
        b=nJss6uVEAM7la9fijRJh/GA3SfCaGTt0FQguIUZOqgxqmwrf3us8BhyAIBoE8bf/DT
         sa7FlAqit6q/iaVIsbPHa5TKHe74YrOOBGZJOzIdCeuDM8VfOW6X/WF5H9OpSoGaqMQh
         z49UBjpVb2VaH2/aIa8mf80Q1fXR7R8LjXcXhYQCKjJzN71xnPR+7PDp2Ym47HmZNZKk
         KmlVMgVcPJSCdFBmhjy0Ycm2KbF3yJynX0MSntx5DKIIiy3wnt9NskoULCbIO4IsFbQx
         rBX0c2hzeyndehr7ae5tIqdsBpS4f202FwN74Z0ixk8vqygwD3+bmSlah0uY1+BgxWdg
         medA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWJR/4DABu+BOu4wcbgAW83PL+ZnvEupf9IIXUatwytWgHHA4gT
	kKL1IqR1N+MTn11g6X0drFA=
X-Google-Smtp-Source: AK7set9PFUus8Vtm5X3l5ekWqpvdO8/UGXPeDH7nzj6Ir4J9eJiyiFShwCzyJNwUaNWFn02GWNF8xg==
X-Received: by 2002:ab0:4a1b:0:b0:68b:9eed:1c7c with SMTP id q27-20020ab04a1b000000b0068b9eed1c7cmr14576546uae.0.1678349144885;
        Thu, 09 Mar 2023 00:05:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:5714:b0:41f:41ea:30ac with SMTP id
 dg20-20020a056102571400b0041f41ea30acls351179vsb.5.-pod-prod-gmail; Thu, 09
 Mar 2023 00:05:44 -0800 (PST)
X-Received: by 2002:a05:6102:53cc:b0:422:1e1f:e5cf with SMTP id bs12-20020a05610253cc00b004221e1fe5cfmr2135650vsb.6.1678349144187;
        Thu, 09 Mar 2023 00:05:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678349144; cv=none;
        d=google.com; s=arc-20160816;
        b=XvF82A3Dk6O4cyJ/FIzNt0BKvhYgDwX4KH9MD862F2JAIe3LCnsf6zmKvPUpU4M1en
         bzbxHYw1jPN40Sw6udq244X2Gf6sWJEYE8vPc66cau4BOXxFYdjSyJwY9lOurLy2JjeI
         VP6bIO4cWPcoNSNFiuQqDx5urH8oV0UvHZ0OYxhexx/tyX8gjESVuzQ0rMY5xFsdYrJY
         kcq25CsdviC4ot0tNmVQqOOP5+K4fVfyxTLJksnVdGfh5hRM/ytUieufjfqOw3lfj5WW
         9MLKU0q1RcqaBQ0DT7EoIbeEdNAmQfH9laDO2Mc0FDqdQsWKAY2Jq+s9gRNu+yDlaCAC
         4ibQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=hj4k34mDfJP5T6OkXp8mvrbJlfZkyElc+T7D5t+IZr4=;
        b=DLFew46p4NbYyYoBYShCzMamzKi9kdxWcHB0mamPdTGESDrW18tONMt8vabcx6TuUD
         yLWrEv88C5vHZY/36ileuatcS4gUDTm4DovPZud+FSVs14DSv0PswSK9AA91Zu9mYyRa
         4sjcKnyRReeIuH6E+7vhq7AvUbbpIjsZT5ZO5wdSKXP7MqMkUyxbLToVtXb6mY0fJaWp
         nL1lD2aqDV/G56Ehhv6xGDlCylCXcwHuOqYMz7TO1AGvv1xSGbu6olDGerGgMbHTiRvN
         29mJDenjJWx/mlMyXkEEkAX9Jc4ks/Rm6P2rspIf0EOpnWC6JKuQ0SERchG2RJo2TuZv
         EWyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=nscrAZx+;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id bx1-20020a0561300a0100b00690829432ebsi1480708uab.2.2023.03.09.00.05.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Mar 2023 00:05:44 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279873.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3296emE5012141;
	Thu, 9 Mar 2023 08:05:39 GMT
Received: from nalasppmta05.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3p76vurpfb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 09 Mar 2023 08:05:39 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA05.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32985cxW006790
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 9 Mar 2023 08:05:38 GMT
Received: from zhenhuah-gv.qualcomm.com (10.80.80.8) by
 nalasex01a.na.qualcomm.com (10.47.209.196) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.986.41; Thu, 9 Mar 2023 00:05:34 -0800
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
To: <catalin.marinas@arm.com>, <will@kernel.org>, <glider@google.com>,
        <elver@google.com>, <dvyukov@google.com>, <akpm@linux-foundation.org>,
        <robin.murphy@arm.com>, <mark.rutland@arm.com>, <jianyong.wu@arm.com>,
        <james.morse@arm.com>
CC: Zhenhua Huang <quic_zhenhuah@quicinc.com>,
        <linux-arm-kernel@lists.infradead.org>, <kasan-dev@googlegroups.com>,
        <linux-mm@kvack.org>, <quic_pkondeti@quicinc.com>,
        <quic_guptap@quicinc.com>, <quic_tingweiz@quicinc.com>
Subject: [PATCH] mm,kfence: decouple kfence from page granularity mapping judgement
Date: Thu, 9 Mar 2023 16:05:22 +0800
Message-ID: <1678349122-19279-1-git-send-email-quic_zhenhuah@quicinc.com>
X-Mailer: git-send-email 2.7.4
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-ORIG-GUID: PFhVf1SZgPqhxlqmii-9SMq9h5EgKF2l
X-Proofpoint-GUID: PFhVf1SZgPqhxlqmii-9SMq9h5EgKF2l
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-09_04,2023-03-08_03,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 mlxscore=0
 suspectscore=0 phishscore=0 mlxlogscore=986 lowpriorityscore=0 bulkscore=0
 clxscore=1011 priorityscore=1501 spamscore=0 adultscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2212070000
 definitions=main-2303090062
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=nscrAZx+;       spf=pass
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
linear mapping setting up, kfence_alloc_pool is to allocate phys addr,
__kfence_pool is to be set after linear mapping set up.

LINK: [1] https://lore.kernel.org/linux-arm-kernel/1675750519-1064-1-git-send-email-quic_zhenhuah@quicinc.com/T/
Suggested-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Zhenhua Huang <quic_zhenhuah@quicinc.com>
---
 arch/arm64/mm/mmu.c      | 24 ++++++++++++++++++++++++
 arch/arm64/mm/pageattr.c |  5 ++---
 include/linux/kfence.h   | 10 ++++++++--
 init/main.c              |  1 -
 mm/kfence/core.c         | 18 ++++++++++++++----
 5 files changed, 48 insertions(+), 10 deletions(-)

diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
index 6f9d889..bd79691 100644
--- a/arch/arm64/mm/mmu.c
+++ b/arch/arm64/mm/mmu.c
@@ -24,6 +24,7 @@
 #include <linux/mm.h>
 #include <linux/vmalloc.h>
 #include <linux/set_memory.h>
+#include <linux/kfence.h>
 
 #include <asm/barrier.h>
 #include <asm/cputype.h>
@@ -532,6 +533,9 @@ static void __init map_mem(pgd_t *pgdp)
 	phys_addr_t kernel_end = __pa_symbol(__init_begin);
 	phys_addr_t start, end;
 	int flags = NO_EXEC_MAPPINGS;
+#ifdef CONFIG_KFENCE
+	phys_addr_t kfence_pool = 0;
+#endif
 	u64 i;
 
 	/*
@@ -564,6 +568,12 @@ static void __init map_mem(pgd_t *pgdp)
 	}
 #endif
 
+#ifdef CONFIG_KFENCE
+	kfence_pool = kfence_alloc_pool();
+	if (kfence_pool)
+		memblock_mark_nomap(kfence_pool, KFENCE_POOL_SIZE);
+#endif
+
 	/* map all the memory banks */
 	for_each_mem_range(i, &start, &end) {
 		if (start >= end)
@@ -608,6 +618,20 @@ static void __init map_mem(pgd_t *pgdp)
 		}
 	}
 #endif
+
+	/* Kfence pool needs page-level mapping */
+#ifdef CONFIG_KFENCE
+	if (kfence_pool) {
+		__map_memblock(pgdp, kfence_pool,
+			kfence_pool + KFENCE_POOL_SIZE,
+			pgprot_tagged(PAGE_KERNEL),
+			NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
+		memblock_clear_nomap(kfence_pool, KFENCE_POOL_SIZE);
+		/* kfence_pool really mapped now */
+		kfence_set_pool(kfence_pool);
+	}
+#endif
+
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
index 726857a..0252e74 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -61,7 +61,12 @@ static __always_inline bool is_kfence_address(const void *addr)
 /**
  * kfence_alloc_pool() - allocate the KFENCE pool via memblock
  */
-void __init kfence_alloc_pool(void);
+phys_addr_t __init kfence_alloc_pool(void);
+
+/**
+ * kfence_set_pool() - KFENCE pool mapped and can be used
+ */
+void __init kfence_set_pool(phys_addr_t addr);
 
 /**
  * kfence_init() - perform KFENCE initialization at boot time
@@ -223,7 +228,8 @@ bool __kfence_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *sla
 #else /* CONFIG_KFENCE */
 
 static inline bool is_kfence_address(const void *addr) { return false; }
-static inline void kfence_alloc_pool(void) { }
+static inline phys_addr_t kfence_alloc_pool(void) { return (phys_addr_t)NULL; }
+static inline void kfence_set_pool(phys_addr_t addr) { }
 static inline void kfence_init(void) { }
 static inline void kfence_shutdown_cache(struct kmem_cache *s) { }
 static inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags) { return NULL; }
diff --git a/init/main.c b/init/main.c
index 4425d17..9aaf217 100644
--- a/init/main.c
+++ b/init/main.c
@@ -839,7 +839,6 @@ static void __init mm_init(void)
 	 */
 	page_ext_init_flatmem();
 	init_mem_debugging_and_hardening();
-	kfence_alloc_pool();
 	report_meminit();
 	kmsan_init_shadow();
 	stack_depot_early_init();
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 5349c37..dd5cdd5 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -809,15 +809,25 @@ static void toggle_allocation_gate(struct work_struct *work)
 
 /* === Public interface ===================================================== */
 
-void __init kfence_alloc_pool(void)
+phys_addr_t __init kfence_alloc_pool(void)
 {
+	phys_addr_t kfence_pool;
 	if (!kfence_sample_interval)
-		return;
+		return 0;
 
-	__kfence_pool = memblock_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
+	kfence_pool = memblock_phys_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
 
-	if (!__kfence_pool)
+	if (!kfence_pool) {
 		pr_err("failed to allocate pool\n");
+		return 0;
+	}
+
+	return kfence_pool;
+}
+
+void __init kfence_set_pool(phys_addr_t addr)
+{
+	__kfence_pool = phys_to_virt(addr);
 }
 
 static void kfence_init_enable(void)
-- 
2.7.4

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1678349122-19279-1-git-send-email-quic_zhenhuah%40quicinc.com.
