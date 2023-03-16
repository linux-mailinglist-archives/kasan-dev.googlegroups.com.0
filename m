Return-Path: <kasan-dev+bncBDVL3PXJZILBB6HCZSQAMGQETCGNOFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id 7BD586BD2F6
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 16:10:49 +0100 (CET)
Received: by mail-qk1-x738.google.com with SMTP id 191-20020a3705c8000000b007459d84a0f9sf1083519qkf.17
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 08:10:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678979448; cv=pass;
        d=google.com; s=arc-20160816;
        b=Bb7CvGoXMYBdGbbhU231/APsaxnmUyan89LUjel6qIf+sW86CImsmkDhOj2UWFDIQK
         ZCfrq0LHB7oIC2X1IwD0ZPYwKDwkgkfUpgj3Rp1BEg86lfr0rCVqajLevoAZPUTLnoko
         iENr4+ikQ920hwgNDMb+PbCIxxfI7oBQKCXWIDfkZApax+M5u/lOsm+pZq71PgA2Wxp1
         8oOIRe04uW/BktYBKi68xtVAeTOfKJkB96B0yTdZ/aGK9gjo9mwO9Vx2QN1fMZ5oJK9A
         OUXPe+pesF19pAhCH27XO9bUpg4xvz/se5CVsArflad9RX1gJ8tNxWc+I0wBrcDj6wCA
         GcUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=1oTnKkMtbuBVuUM35ThxEsHBcDPpUk/5iApmWfQ5pQ4=;
        b=g1UBXlJiRnatNUx90wzdhGe+pZi6s84fZFePC5xt/Men2uO4kMpszdranPmTp3lfGo
         ZG3731dcLY+qurE2S+YPU2rQkpX94sVFh9LCYIN16z60ulE8scmajd0o5kCRF15YctUJ
         YG3obusr/iqwdbV/5glEDK9jO1hYkM4nkwGZ7nozqNxxvcVsn/jXkCqg9Xh3b+kTp0nx
         gDlYcTgQZ7Pm3u4bCT3BU5cYIkdaXHPlREdZY9E/+31tf0GOq90Mp2tSxuc8QhoOFGBc
         ja1hw+nptS4ouMiFtIhQ998+us3O2fXqDZYRyX2Jw6ZltSdx+WX9kaFcCpOzaA6fKc7M
         Wxhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b="V/90ROiP";
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678979448;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1oTnKkMtbuBVuUM35ThxEsHBcDPpUk/5iApmWfQ5pQ4=;
        b=ThRZmSA8QR43buTCbnwfhSxFnUwHmSU6ItXur4EodhnszKaeYELpQjPliDO0a4ared
         sXG0lYKCdB0ypsEHk4qxp5LE6Lv3evcRiZIzvgL3UORJyTJg01OF9yJ7UnQJyIHnItLx
         h5cEUhcAuAHrG1EU1bgJKIgp3Bg7GlZkj/feI7ss/6TBYUpCjH/ALJxkDGV/+qOBYv7f
         IbHzwLgMlYp7gMP6tK7qLAqSav+bX3fnsMuQw6Ocwnq/WUTP967gv+2DExcS3KxaGWMj
         5VSktyGg5m9Q2ahme76XlsiuVb3vcXVpGBBCR5FyG/LNcXWQ6gcPd1+2GaAtBUZpAsb1
         o+Kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678979448;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=1oTnKkMtbuBVuUM35ThxEsHBcDPpUk/5iApmWfQ5pQ4=;
        b=29MYxaZ4M+iPlybSlRIR8cxzfzD2erQu3wDjwp8Ji0ddMZUOC2V/n+phipsW/q67Io
         Xerjj6D9eUjZOxRVt3ADlRV6tMzAsUoFF1R8z49Hj3Jr2m4kH1Sd5cZ77YSQh1f+BViY
         w+QX9rcJucj76xAnbQb+a4YYMPzRMX+iwn6BCA41AXJrL2v8xcWPr1RhdwI7wbwfvyWS
         oq34wa8FSNQX88pSVaj1RBEI6OSeURSz5PtDBSBX4yKB9Frb70nLTar1QaDjU13/VHNR
         KxrWN/TtOxk33jDn1iX3vAJVaHgLKAxDPyPuR/3vN5zYXMEN6ltx2uJhDDmh0DhWRaqd
         oDRQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUfTuW7wXCRsrtquuKASYCa+slT+5MBmlbPbCv/YE1Fe0dCHyXx
	tfssZaOOXRd4PHS4UDx9+u8=
X-Google-Smtp-Source: AK7set9+JD6mwGpAIJb6vW9d4c2b0ntJ4OlfY1Y8gmsNsSbPxTg/XrL9PSw56J9zL/fsrGCZWsrBWg==
X-Received: by 2002:a05:620a:5c:b0:742:7e2b:68d2 with SMTP id t28-20020a05620a005c00b007427e2b68d2mr5481938qkt.7.1678979448248;
        Thu, 16 Mar 2023 08:10:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:4895:b0:3b9:bfda:1fa8 with SMTP id
 fc21-20020a05622a489500b003b9bfda1fa8ls2188637qtb.3.-pod-prod-gmail; Thu, 16
 Mar 2023 08:10:47 -0700 (PDT)
X-Received: by 2002:ac8:598a:0:b0:3b9:b6c8:6d5b with SMTP id e10-20020ac8598a000000b003b9b6c86d5bmr7531593qte.35.1678979447671;
        Thu, 16 Mar 2023 08:10:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678979447; cv=none;
        d=google.com; s=arc-20160816;
        b=kbVMpynajCcNstIY+lgRwDmb8We2uEMuX8ARGuC8VXT3nKINoXXQ/a24kjAn//VFP0
         Aj31FITHEh27GpjBqC4TnJpIQupofNFNjcXN4R7wZYpRPUhTRk5xgOn+92jmJEytyaLt
         C/pqjq8xZy/jMWwGX8vda/5hT675JfTwibNgkGfLpCAxb6cdLDGMa+0Dw4PWWKBEQN4j
         EGZ+vdjrdKDPcvKNAMQUtfugz8bO8NVOCeR7K0O1WhdyzBKPT+UsqeDAU5MR4xFmWTEz
         fD3/cHw+LTxbxOCMkbVtLLJOZwg3fWn0g68nmndYc60zk0vzsanKPGy6o0EON70ZGpSX
         fCXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=eHdTtV0lBgYizUaeyP96VkwCxTWvoPj/T5orJccIOJQ=;
        b=zi593CQ8dObxD/84F7bbgoZ4XjnmzRbNhZyLHs7X1kRVq0/b9hm9uNgGhR0Mtp9NC6
         Y6fJiRzkm0GDlTD9yLTOWOOyImyXNF8HgNpln0d3CsP/CxiUJeTyKyEPaicuuNEmIGnJ
         WZqdmuhkEDHkYX8NTMvbj1EMOW/wOgkZkRYxRKueqUCOighF5GEkPhFL7g86rPJK4jeF
         Ywa3vD10HpbZW2VCDjMH+GrgGufXZRbplRPGC1q8XT8Y4a8vOzaBDP1TI4AQ6mdxyuh3
         o4e+UHTc0ASnViA4FE8SLqBP7XxrK1KEY+1tkmGsmZo7eLaqtcSJFkwLgCmgZkVfW5FY
         nufg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b="V/90ROiP";
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id ee22-20020a05620a801600b00725bdb9a8acsi447440qkb.5.2023.03.16.08.10.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Mar 2023 08:10:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279871.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 32G24u4Z014889;
	Thu, 16 Mar 2023 15:10:42 GMT
Received: from nalasppmta03.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3pbpy9j8ay-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Mar 2023 15:10:42 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA03.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32GFAfSv019229
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Mar 2023 15:10:41 GMT
Received: from zhenhuah-gv.qualcomm.com (10.80.80.8) by
 nalasex01a.na.qualcomm.com (10.47.209.196) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.986.41; Thu, 16 Mar 2023 08:10:36 -0700
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
To: <catalin.marinas@arm.com>, <will@kernel.org>, <glider@google.com>,
        <elver@google.com>, <dvyukov@google.com>, <akpm@linux-foundation.org>,
        <robin.murphy@arm.com>, <mark.rutland@arm.com>, <jianyong.wu@arm.com>,
        <james.morse@arm.com>, <wangkefeng.wang@huawei.com>
CC: Zhenhua Huang <quic_zhenhuah@quicinc.com>,
        <linux-arm-kernel@lists.infradead.org>, <kasan-dev@googlegroups.com>,
        <linux-mm@kvack.org>, <quic_pkondeti@quicinc.com>,
        <quic_guptap@quicinc.com>, <quic_tingweiz@quicinc.com>
Subject: [PATCH v11] mm,kfence: decouple kfence from page granularity mapping judgement
Date: Thu, 16 Mar 2023 23:10:29 +0800
Message-ID: <1678979429-25815-1-git-send-email-quic_zhenhuah@quicinc.com>
X-Mailer: git-send-email 2.7.4
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01a.na.qualcomm.com (10.52.223.231) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-ORIG-GUID: 64gGpA0whIXuddshqb5pVFaTvAnN2oM3
X-Proofpoint-GUID: 64gGpA0whIXuddshqb5pVFaTvAnN2oM3
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-16_10,2023-03-16_01,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 clxscore=1015 mlxlogscore=999 suspectscore=0 spamscore=0 malwarescore=0
 mlxscore=0 priorityscore=1501 bulkscore=0 adultscore=0 phishscore=0
 impostorscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2303150002 definitions=main-2303160122
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b="V/90ROiP";       spf=pass
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
Reviewed-by: Kefeng Wang <wangkefeng.wang@huawei.com>
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
index 6f9d889..9813f2a 100644
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
@@ -525,12 +527,67 @@ static int __init enable_crash_mem_map(char *arg)
 }
 early_param("crashkernel", enable_crash_mem_map);
 
+#ifdef CONFIG_KFENCE
+
+bool __ro_after_init kfence_early_init = !!CONFIG_KFENCE_SAMPLE_INTERVAL;
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
+static phys_addr_t __init arm64_kfence_alloc_pool(void)
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
+static void __init arm64_kfence_map_pool(phys_addr_t kfence_pool, pgd_t *pgdp)
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
 
@@ -543,6 +600,8 @@ static void __init map_mem(pgd_t *pgdp)
 	 */
 	BUILD_BUG_ON(pgd_index(direct_map_end - 1) == pgd_index(direct_map_end));
 
+	early_kfence_pool = arm64_kfence_alloc_pool();
+
 	if (can_set_direct_map())
 		flags |= NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
 
@@ -608,6 +667,8 @@ static void __init map_mem(pgd_t *pgdp)
 		}
 	}
 #endif
+
+	arm64_kfence_map_pool(early_kfence_pool, pgdp);
 }
 
 void mark_rodata_ro(void)
diff --git a/arch/arm64/mm/pageattr.c b/arch/arm64/mm/pageattr.c
index 79dd201..8e2017b 100644
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
index 5349c37..5abc79f 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -814,6 +814,10 @@ void __init kfence_alloc_pool(void)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1678979429-25815-1-git-send-email-quic_zhenhuah%40quicinc.com.
