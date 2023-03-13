Return-Path: <kasan-dev+bncBDVL3PXJZILBBMM7XSQAMGQEKNR24OI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 442A66B76FF
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Mar 2023 12:57:39 +0100 (CET)
Received: by mail-oo1-xc40.google.com with SMTP id y9-20020a4acb89000000b0051760012060sf3198455ooq.16
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Mar 2023 04:57:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678708658; cv=pass;
        d=google.com; s=arc-20160816;
        b=vshcblOYq+ITTMmi5X/AcnG1tTa/mKdJEyCNBDV79thPjurQycsHWzefrNKKw91Pmr
         VXE2J/IXJjs33lWfNnS89DWNNNG2dChh/TgH3fr7ujockf4dMdyYmKZdI5QN04VHrLM3
         1OYPyL242gv6fK2s7DC3u89WZsNgJYnaljv7d2FZ0JQ2m9tzCE2zz7jMOwcwjEVbyXdR
         oKHW/0V/wmiytbaDkqyT3WPYR35PN0vuhEV1TuTS/qRsf/QkAFOGJpUukILYTDES3Q6p
         7WTiRcesK6jvHIAXGMPpLRohSSYppwBVnLAQEkwdcw7ZwSU6s56SBhg585K+vHY6GVFo
         eFZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=W8s9k+6Ws0l7+X2GB/xTc6EiJ9BBNeS+Ra/qXGjvoys=;
        b=bhF1IMNS8in1xjpvNq9B1Vk8yjJ3ugGGs7JJV65LFngUlKbqNMSC6bwKwwTY0qRqHz
         RtrIQYVrBvw/9EIApbOGAdSQS7zgJMJNkXBrjKlYMOqGnphT7HeAsmAtSDCublaFRnA0
         W7hsMoeZyVMPhjfp4RtwHjyCPa8QlGGQGxK4BhGFvOWLOM/lhknjOzWeaUplAtV+d0fH
         5uCs+eDDQMVUGVRmEaOyxSkiPqowloEVTURSCBtX5qfqDf071j4buNGrAuIURZaL9Zq0
         AB+lciDC7ycd71ybBrfyETW+kUgYtAMTnBCI6r9cMFjsluwl18XEmjlzv9epx1XE98QJ
         9zdg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=nt6ubkNZ;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678708658;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=W8s9k+6Ws0l7+X2GB/xTc6EiJ9BBNeS+Ra/qXGjvoys=;
        b=OfNDEiQC+xfDwgcHKnTnZLCfBg6ivnTVjS+FnzAouMYe2OJGgWmNKxQrodYktvEg+O
         S1V/ow7YQ15KjmycsF5PQtv4TtAOe08V82xDCdE2TmOxlFEbkWBBA/pYwk31g8FPJ/YT
         /nVkxiB3ENijp4UW5ppHTI1sSVwK1UjEubH/Cwe4OOSnZROLygVYajlDq00neMnGMfVa
         gqN/nvQwTaV/RFzvqrdGvOwPLjDjxo15wXX7tduFx22pZFATuHyH5GfG9ZcTQEUi09Ap
         qYjqNMDkCgBbwxR2KRQS1426zkGuJ7h+HEqfMWD1793WbSg1ararUcVpqZ93Az1+EK2z
         YVuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678708658;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=W8s9k+6Ws0l7+X2GB/xTc6EiJ9BBNeS+Ra/qXGjvoys=;
        b=O2U5p4kSqCjCNsifJBe0wTyFk2YZAvYbCE2XIC93iV5MxZx4Mdyt18ZGCvyTAMqNQ+
         KA7x77FwUByhDXUZkWQooqLI2C/wv01lb5QKt1vtbsZyHbfHHHL2+0Xq2NOKo6d0pX8M
         KIjdMt4VMQvGUixcixNFrEJIzlcdobDWmetq+7HF1gibzpDdG+Ww+R4QCl+XMONFpk1R
         ArBc2vffcsRTIcWcWcYjOy4nTzpFm3RGg3CfyLpbq/Us/BZV2ac+g6zgqYeevt7GSvnY
         pbBMV0AeAytYNVdL+gT0MVrsl99bbiCKr9qNXQpC0qBZM2mD9339xiSdGgcCpusMpHtn
         LwOA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVhed9kkc7wk+AibSRi80qp9RtQQLfhRCe+9YAAX1ppT7OdsTkG
	aprQr/QaLcNYBqFEgbhNEdo=
X-Google-Smtp-Source: AK7set+/Zhd7qi4p7FwG8EFwm5OJ+AJhToeq/oRgbb5yvn2DE/oyAiUBdvHO+jG1vpf9uOLVkPnyRw==
X-Received: by 2002:a05:6870:c384:b0:16e:2f74:e5c1 with SMTP id g4-20020a056870c38400b0016e2f74e5c1mr9279079oao.8.1678708657886;
        Mon, 13 Mar 2023 04:57:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:685:0:b0:384:8e58:2a3c with SMTP id 127-20020aca0685000000b003848e582a3cls4046981oig.6.-pod-prod-gmail;
 Mon, 13 Mar 2023 04:57:37 -0700 (PDT)
X-Received: by 2002:a05:6808:8b:b0:37f:a534:3dfa with SMTP id s11-20020a056808008b00b0037fa5343dfamr16421266oic.20.1678708657320;
        Mon, 13 Mar 2023 04:57:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678708657; cv=none;
        d=google.com; s=arc-20160816;
        b=O6+Az60VJozryJxUyfNkc5CQp0LGiEZMFYVGwilgT9mlo+b5ZrVFDvTllYHrWFoanl
         RUtAb3OAm+roDLDiBR1eyGNIspr4fpWSMdJhGeZlZtR5D9PoZcqJMF7viNeqZm7UwYVQ
         Kc3n276lyh1O3BCIHLCKolitY5Gcqjqkkfjf84ymBwyr0i/zjLkIsj5n1U49nkHCtkuP
         R8EqIqO9RgiyQ1VjxmM1BL6Rm7QMoDCodcdp58TXV8CHdPJC9rs5NKsZwKp0e0P6Uz7C
         MYMzZ/pM8Dt1yBvc2CpON3neJEXE38IKkGJNZfnJXs16gU96q+cg+9bNZ4y8NB/5sYCC
         8G+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=kzU56oRMq1BLyfE79pFBanLtUrgRyEEuF+2+50JBPf8=;
        b=eHAbImpnLNT2WujbvaM3OuYVVuztHPOGmWrG4hhFpEHOz+Y+eUs0C+ezS4MaFUBHPh
         a7YnuN3AQTDzxtxLpI+p68ukrzbw2+ywnrx4Qwvt/yOwaihMWE6qR+p36uAQmhtJY1F5
         WYcoYVfhH7egkyyc299+wmvVkdf29YoDLO8En007Lumy6GrE05Pv9X8ANufzVLXmhoTm
         ETt8S9JuEy2ppTwRoa5tDLzdOSvAE8geEjPEacnyEBUC2ohtMxlpWmNcDT1JPp+JtQKZ
         9jzdSd+CaEnePPq4Zi9sAARoZ5K+DZqrc/1DjxJvaw7d/fvwcKWovoyP6I8KJuk0DeM2
         2lBQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=nt6ubkNZ;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id x29-20020a4a9b9d000000b00525240a102asi668757ooj.1.2023.03.13.04.57.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 13 Mar 2023 04:57:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279871.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 32DBAsNl004085;
	Mon, 13 Mar 2023 11:57:31 GMT
Received: from nalasppmta04.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3p8h88mnbt-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 13 Mar 2023 11:57:31 +0000
Received: from nalasex01b.na.qualcomm.com (nalasex01b.na.qualcomm.com [10.47.209.197])
	by NALASPPMTA04.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32DBvUKE021983
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 13 Mar 2023 11:57:30 GMT
Received: from zhenhuah-gv.qualcomm.com (10.80.80.8) by
 nalasex01b.na.qualcomm.com (10.47.209.197) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.986.41; Mon, 13 Mar 2023 04:57:25 -0700
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
To: <catalin.marinas@arm.com>, <will@kernel.org>, <glider@google.com>,
        <elver@google.com>, <dvyukov@google.com>, <akpm@linux-foundation.org>,
        <robin.murphy@arm.com>, <mark.rutland@arm.com>, <jianyong.wu@arm.com>,
        <james.morse@arm.com>, <wangkefeng.wang@huawei.com>
CC: Zhenhua Huang <quic_zhenhuah@quicinc.com>,
        <linux-arm-kernel@lists.infradead.org>, <kasan-dev@googlegroups.com>,
        <linux-mm@kvack.org>, <quic_pkondeti@quicinc.com>,
        <quic_guptap@quicinc.com>, <quic_tingweiz@quicinc.com>
Subject: [PATCH v6] mm,kfence: decouple kfence from page granularity mapping judgement
Date: Mon, 13 Mar 2023 19:57:17 +0800
Message-ID: <1678708637-8669-1-git-send-email-quic_zhenhuah@quicinc.com>
X-Mailer: git-send-email 2.7.4
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nalasex01b.na.qualcomm.com (10.47.209.197)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: iaTz0-yEuRVqmrCL0KyIoiv5drwO_M1G
X-Proofpoint-ORIG-GUID: iaTz0-yEuRVqmrCL0KyIoiv5drwO_M1G
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-13_05,2023-03-13_01,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015
 priorityscore=1501 mlxscore=0 spamscore=0 bulkscore=0 phishscore=0
 impostorscore=0 lowpriorityscore=0 suspectscore=0 malwarescore=0
 mlxlogscore=999 adultscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2212070000 definitions=main-2303130098
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=nt6ubkNZ;       spf=pass
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
 arch/arm64/mm/mmu.c      | 42 ++++++++++++++++++++++++++++++++++++++++++
 arch/arm64/mm/pageattr.c |  8 ++++++--
 include/linux/kfence.h   | 10 ++++++++++
 mm/kfence/core.c         |  9 +++++++++
 4 files changed, 67 insertions(+), 2 deletions(-)

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
index 79dd201..25e4a983 100644
--- a/arch/arm64/mm/pageattr.c
+++ b/arch/arm64/mm/pageattr.c
@@ -7,6 +7,7 @@
 #include <linux/module.h>
 #include <linux/sched.h>
 #include <linux/vmalloc.h>
+#include <linux/kfence.h>
 
 #include <asm/cacheflush.h>
 #include <asm/set_memory.h>
@@ -22,12 +23,15 @@ bool rodata_full __ro_after_init = IS_ENABLED(CONFIG_RODATA_FULL_DEFAULT_ENABLED
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
+	    (IS_ENABLED(CONFIG_KFENCE) && !kfence_sample_interval);
 }
 
 static int change_page_range(pte_t *ptep, unsigned long addr, void *data)
diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index 726857a..2b77eee 100644
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
@@ -222,8 +228,12 @@ bool __kfence_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *sla
 
 #else /* CONFIG_KFENCE */
 
+extern unsigned long kfence_sample_interval;
+
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1678708637-8669-1-git-send-email-quic_zhenhuah%40quicinc.com.
